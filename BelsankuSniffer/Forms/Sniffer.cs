using System;
using System.Drawing;
using System.Windows.Forms;
using System.Net.Sockets;
using System.Net;
using System.Net.NetworkInformation;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Data;

namespace BelsankuSniffer
{
    public partial class Sniffer : Form
    {
        public Sniffer()
        {
            InitializeComponent();
        }

        /// <summary>
        /// Массив интерфейсов
        /// </summary>
        private NetworkInterface[] networkInterfaces = NetworkInterface.GetAllNetworkInterfaces();

        /// <summary>
        /// отображение и прослушка сокетов
        /// </summary>
        private Monitor currentMonitor;

        private List<Monitor> monitorList = new List<Monitor>();

        /// <summary>
        /// Содержимое таблицы
        /// </summary>
        private DataTable dataTable = new DataTable();

        /// <summary>
        /// Столбцы таблицы
        /// </summary>
        private void LoadControls()
        {
            dataTable.Columns.Add("source_ip");
            dataTable.Columns.Add("source_port");
            dataTable.Columns.Add("destination_ip");
            dataTable.Columns.Add("destination_port");
            dataTable.Columns.Add("protocol");
            dataTable.Columns.Add("time");
            dataTable.Columns.Add("length", typeof(int));
            dataTable.Columns.Add("data");

            // скрытые столбцы
            dataTable.Columns.Add("hex");
            dataTable.Columns.Add("raw", typeof(byte[]));

            DGV.AutoGenerateColumns = false;
            DGV.DataSource = dataTable;
            DGV.Columns["SourceIp"].DataPropertyName = "source_ip";
            DGV.Columns["SourcePort"].DataPropertyName = "source_port";
            DGV.Columns["DestinationIp"].DataPropertyName = "destination_ip";
            DGV.Columns["DestinationPort"].DataPropertyName = "destination_port";
            DGV.Columns["Protocol"].DataPropertyName = "protocol";
            DGV.Columns["Time"].DataPropertyName = "time";
            DGV.Columns["Length"].DataPropertyName = "length";
            DGV.Columns["Data"].DataPropertyName = "data";

            // Hidden columns
            DGV.Columns["Hex"].DataPropertyName = "hex";
            DGV.Columns["Raw"].DataPropertyName = "raw";

            for (var i = 0; i <= networkInterfaces.Length - 1; i++)
                cbInterfaces.Items.Add(networkInterfaces[i].Name);

            cbInterfaces.SelectedIndex = 0;
        }

        /// <summary>
        ///прослушивание интерфейса и получение с него пакетов
        /// </summary>
        /// <returns>True, если можно получать пакеты и False, если нельзя.</returns>
        private bool StartReceiving()
        {
            if (cbInterfaces.SelectedIndex == 0) // Все интерфейсы
            {
                monitorList.Clear();
                IPAddress[] hosts = Dns.GetHostEntry(Dns.GetHostName()).AddressList;

                for (int i = 0; i < hosts.Length; i++)
                {
                    Monitor monitor = new Monitor(hosts[i]);
                    monitor.PacketEventHandler += new Monitor.NewPacketEventHandler(OnNewPacket);
                    monitorList.Add(monitor);
                }

                foreach (Monitor monitor in monitorList)
                {
                    monitor.Start();
                }
                return true;
            }
            else
            {
                int index = cbInterfaces.SelectedIndex - 1;

                IPAddress myIp = null;
                IPInterfaceProperties interfaceProperties = networkInterfaces[index].GetIPProperties();

                for (int i = 0; i <= interfaceProperties.UnicastAddresses.Count - 1; i++)
                {
                    if (interfaceProperties.UnicastAddresses[i].Address.AddressFamily == AddressFamily.InterNetwork)
                    {
                        myIp = interfaceProperties.UnicastAddresses[i].Address;
                    }
                }

                try
                {
                    currentMonitor = new Monitor(myIp);
                    currentMonitor.PacketEventHandler += new Monitor.NewPacketEventHandler(OnNewPacket);
                    currentMonitor.Start();
                    return true;
                }
                catch (Exception e)
                {
                    MessageBox.Show("Не могу прослушать " + networkInterfaces[index].Name + " Ошибка: " + e, "Ошибка соединения", default, MessageBoxIcon.Error);
                    return false;
                }
            }
            
        }

        /// <summary>
        /// остановка захвата.
        /// </summary>
        private void StopReceiving()
        {
            if (cbInterfaces.SelectedIndex == 0) // все интерфейсы
            {
                foreach (Monitor monitor in monitorList)
                {
                    monitor.Stop();
                }
            }
            else
            {
                currentMonitor.Stop();
            }
                
        }

        /// <summary>
        /// инвок метода после каждого полученного пакета
        /// </summary>
        /// <param name="monitor">Отображение полученного пакета.</param>
        /// <param name="p">Пакет получен.</param>
        private void OnNewPacket(Monitor monitor, Packet p) => Invoke(new refresh(OnRefresh), p);

        private delegate void refresh(Packet p);

        /// <summary>
        /// обновление таблицы при получении пакета
        /// </summary>
        /// <param name="p">Пакет получен.</param>
        private void OnRefresh(Packet p)
        {
            dataTable.Rows.Add(new object[]
            {
                p.SourceIp, p.SourcePort, p.DestinationIP, p.DestinationPort, p.Protocol, p.Time, p.TotalLength, p.CharString, p.HexString, p.Bytes
            });
            ColorRows();

            if (DGV.Rows.Count != 0 && btnAutomaticScroll.Checked)
            {
                DGV.FirstDisplayedScrollingRowIndex = DGV.RowCount - 1;
            }
        }

        /// <summary>
        /// Установка фильтра
        /// </summary>
        private void FilterDGV()
        {
            string filter = tbFilter.Text;
            DataTable dataTable = (DataTable) DGV.DataSource;
            DataView dataView = new DataView(dataTable);
            try
            {
                if (string.IsNullOrEmpty(filter))
                {
                    dataTable.DefaultView.RowFilter = "";
                    tbFilter.BackColor = Color.White;
                } 
                else
                {
                    dataTable.DefaultView.RowFilter = filter;
                    tbFilter.BackColor = Color.LimeGreen;
                }
            }
            catch (Exception msg)
            {
                Console.WriteLine(msg.Message);
                dataTable.DefaultView.RowFilter = "";
                tbFilter.BackColor = Color.Crimson;
            }
            finally
            {
                ColorRows();
            }
        }

        /// <summary>
        /// Цвета для пакетов
        /// </summary>
        private void ColorRows()
        {
            if (btnPacketColoring.Checked)
            {
                foreach (DataGridViewRow row in DGV.Rows)
                {
                    string protocol = Convert.ToString(row.Cells["Protocol"].Value);

                    switch (protocol)
                    {
                        case "TCP":
                            row.DefaultCellStyle.BackColor = Color.Lavender;
                            break;
                        case "UDP":
                            row.DefaultCellStyle.BackColor = Color.LightCyan;
                            break;
                        case "GGP":
                            row.DefaultCellStyle.BackColor = Color.Aquamarine;
                            break;
                        case "ICMP":
                            row.DefaultCellStyle.BackColor = Color.Bisque;
                            break;
                        case "IDP":
                            row.DefaultCellStyle.BackColor = Color.LightPink;
                            break;
                        case "IGMP":
                            row.DefaultCellStyle.BackColor = Color.PaleGreen;
                            break;
                        case "IP":
                            row.DefaultCellStyle.BackColor = Color.LightYellow;
                            break;
                        case "ND":
                            row.DefaultCellStyle.BackColor = Color.Thistle;
                            break;
                        case "PUP":
                            row.DefaultCellStyle.BackColor = Color.BlanchedAlmond;
                            break;
                        case "OTHERS":
                            row.DefaultCellStyle.BackColor = Color.WhiteSmoke;
                            break;
                    }
                }
            }
            else
            {
                foreach (DataGridViewRow row in DGV.Rows)
                {
                    row.DefaultCellStyle.BackColor = Color.White;
                }
            }
        }

        /// <param name="index">индекс строки.</param>
        private void SetSelectedRow(int index)
        {
            if (index >= 0 && index < DGV.RowCount)
            {
                DGV.CurrentCell = DGV.Rows[index].Cells[0];
                DGV_CellClick(this, new DataGridViewCellEventArgs(0, index));
            }
        }

        /// <summary>
        /// экспорт .txt
        /// </summary>
        private void ExportPacketsAsText()
        {
            if (DGV.RowCount > 0)
            {
                SaveFileDialog sfd = new SaveFileDialog
                {
                    Filter = "Text Files(*.txt)|*.txt",
                    Title = "Экспорт пакетов в .TXT",
                    FileName = "packets.txt"
                };

                if (sfd.ShowDialog() == DialogResult.OK)
                {
                    using (StreamWriter sw = new StreamWriter(sfd.OpenFile()))
                    {
                        sw.WriteLine("---------------------------------------------\n");

                        foreach (DataGridViewRow row in DGV.Rows)
                        {
                            string sourceIP = row.Cells["SourceIp"].Value.ToString();
                            string sourcePort = row.Cells["SourcePort"].Value.ToString();
                            string destinationIP = row.Cells["DestinationIp"].Value.ToString();
                            string destinationPort = row.Cells["DestinationPort"].Value.ToString();
                            string protocol = row.Cells["Protocol"].Value.ToString();
                            string time = row.Cells["Time"].Value.ToString();
                            string length = row.Cells["Length"].Value.ToString();
                            string data = row.Cells["Data"].Value.ToString();

                            sw.WriteLine(string.Format("{0, -20}{1}", "Протокол:", protocol));
                            sw.WriteLine(!string.IsNullOrEmpty(sourcePort) ?
                                string.Format("{0, -20}{1}", "Источник:", sourceIP + ":" + sourcePort) :
                                string.Format("{0, -20}{1}", "Источник:", sourceIP));
                            sw.WriteLine(!string.IsNullOrEmpty(destinationPort) ?
                                string.Format("{0, -20}{1}", "Назначение:", destinationIP + ":" + destinationPort) :
                                string.Format("{0, -20}{1}", "Назначение:", destinationIP));
                            sw.WriteLine(string.Format("{0, -20}{1} bytes", "Длина:", length));
                            sw.WriteLine(string.Format("{0, -20}{1}", "Время:", time));
                            sw.WriteLine("\nСодержимое:");
                            sw.WriteLine(data.Length > 0 ?
                                data :
                                "Пусто\n");
                            sw.WriteLine("---------------------------------------------\n");
                        }

                        sw.Flush();
                        sw.Close();
                    }
                }
            }
            else
            {
                MessageBox.Show("Нет пакетов для экспорта", "Экспорт пакетов .txt", default, MessageBoxIcon.Warning);
            }
        }

        /// <summary>
        /// экспорт .bin
        /// </summary>
        private void ExportSelectedPacketAsBinary()
        {
            if (DGV.SelectedRows.Count == 1)
            {
                SaveFileDialog sfd = new SaveFileDialog
                {
                    Filter = "Binary Files(*.bin)|*.bin",
                    Title = "Экспорт пакетов в .BIN",
                    FileName = "packet_data.bin"
                };

                if (sfd.ShowDialog() == DialogResult.OK)
                {
                    using (StreamWriter sw = new StreamWriter(sfd.OpenFile()))
                    {

                        DataGridViewRow selectedRow = DGV.CurrentRow;
                        byte[] bytes = (byte[]) selectedRow.Cells["Raw"].Value;

                        foreach (byte b in bytes)
                            sw.Write((char)b);

                        sw.Flush();
                        sw.Close();
                    }
                }
            } 
            else
            {
                MessageBox.Show("Выберите пакет", "Экспорт байтов пакета", default, MessageBoxIcon.Warning);
            }
        }

        /// <summary>
        /// экспорт .csv
        /// </summary>
        private void ExportPacketsAsCsv()
        {
            if (DGV.RowCount > 0)
            {
                SaveFileDialog sfd = new SaveFileDialog
                {
                    Filter = "CSV Files(*.csv)|*.csv",
                    Title = "Экспорт пакетов в .CSV",
                    FileName = "packets.csv"
                };

                if (sfd.ShowDialog() == DialogResult.OK)
                {
                    int columnCount = DGV.Columns.Count - 2;
                    string columnNames = "";
                    string[] outputCsv = new string[DGV.Rows.Count + 1];
                    for (int i = 0; i < columnCount; i++)
                    {
                        columnNames += DGV.Columns[i].HeaderText.ToString() + ",";
                    }
                    outputCsv[0] += columnNames;

                    for (int i = 1; (i - 1) < DGV.Rows.Count; i++)
                    {
                        for (int j = 0; j < columnCount; j++)
                        {
                            if (j != 7)
                            {
                                outputCsv[i] += DGV.Rows[i - 1].Cells[j].Value.ToString() + ",";
                            }
                            else // Data column
                            {
                                outputCsv[i] += '"' + DGV.Rows[i - 1].Cells[j].Value.ToString().Replace("\n", "") + '"' + ",";
                            }
                        }
                    }

                    File.WriteAllLines(sfd.FileName, outputCsv, Encoding.UTF8);
                }
            } 
            else
            {
                MessageBox.Show("Нет пакетов для экспорта", "Экспорт пакетов .csv", default, MessageBoxIcon.Warning);
            }
        }

        // СОБЫТИЯ

        private void Sniffer_Load(object sender, EventArgs e)
        {
            LoadControls();
        }

        private void btnStart_Click(object sender, EventArgs e)
        {
            if (StartReceiving())
            {
                btnStart.Enabled = false;
                btnStop.Enabled = true;
                btnExportToText.Enabled = false;
                btnExportToCsv.Enabled = false;
                btnExportBytesFromSelected.Enabled = false;
                cbInterfaces.Enabled = false;
            }
        }

        private void btnStop_Click(object sender, EventArgs e)
        {
            StopReceiving();
            btnStart.Enabled = true;
            btnStop.Enabled = false;
            btnExportToText.Enabled = true;
            btnExportToCsv.Enabled = true;
            btnExportBytesFromSelected.Enabled = true;
            cbInterfaces.Enabled = true;
        }

        private void btnClear_Click(object sender, EventArgs e)
        {
            dataTable.Rows.Clear();
            rtbHexadecimal.Text = "";
            rtbChars.Text = "";
        }

        private void DGV_CellClick(object sender, DataGridViewCellEventArgs e)
        {
            int index = e.RowIndex;

            if (index >= 0)
            {
                DataGridViewRow dataRow = DGV.Rows[index];
                rtbHexadecimal.Text = dataRow.Cells["hex"].Value.ToString();
                rtbChars.Text = dataRow.Cells["data"].Value.ToString();
            }
        }

        private void DGV_Sorted(object sender, EventArgs e) => ColorRows();

        private void rtbChars_SelectionChanged(object sender, EventArgs e)
        {
            string dataText = rtbChars.Text;
            string selectedText = rtbChars.SelectedText;
            int selectedLength = selectedText.Length;

            int start0 = rtbChars.SelectionStart - selectedLength;
            int start1 = rtbChars.SelectionStart;

            int index = start0 > -1 && dataText.Substring(start0, selectedLength).Equals(selectedText) ? start0 : start1;
            string tmpString = rtbChars.Text.Substring(0, index);
            int spaceCount = getCharCount(tmpString, '\n');

            int start = tmpString.Length * 3 - 2 * spaceCount;
            int selectedHexLength = rtbChars.SelectedText.Length * 3 - 2 * getCharCount(rtbChars.SelectedText, '\n');
            if (selectedHexLength > 0)
            {
                rtbHexadecimal.SelectionStart = 0;
                rtbHexadecimal.SelectionLength = rtbHexadecimal.Text.Length;
                rtbHexadecimal.SelectionBackColor = Color.White;

                rtbHexadecimal.SelectionStart = start;
                rtbHexadecimal.SelectionLength = selectedHexLength;
                rtbHexadecimal.SelectionBackColor = Color.CornflowerBlue;
            }
            else
            {
                rtbHexadecimal.SelectionBackColor = Color.White;
            }

            int getCharCount(string s, char c)
            {
                int count = 0;
                for (int i = 0; i < s.Length; i++)
                {
                    if (s[i] == c)
                        count++;
                }
                return count;
            }
        }

        private void rtbChars_Leave(object sender, EventArgs e) => rtbHexadecimal.SelectionBackColor = Color.White;

        private void cbProtocol_SelectionChangeCommitted(object sender, EventArgs e) => FilterDGV();

        private void tbFilter_TextChanged(object sender, EventArgs e) => FilterDGV();

        private void btnPrevious_Click(object sender, EventArgs e) => SetSelectedRow(DGV.CurrentRow != null ? DGV.CurrentRow.Index - 1 : 0);

        private void btnNext_Click(object sender, EventArgs e) => SetSelectedRow(DGV.CurrentRow != null ? DGV.CurrentRow.Index + 1 : 0);

        private void btnFirst_Click(object sender, EventArgs e) => SetSelectedRow(0);

        private void btnLast_Click(object sender, EventArgs e) => SetSelectedRow(DGV.RowCount - 1);

        private void btnQuit_Click(object sender, EventArgs e) => Application.Exit();

        private void btnPacketColoring_Click(object sender, EventArgs e) => ColorRows();

        private void btnExportToText_Click(object sender, EventArgs e) => ExportPacketsAsText();

        private void btnExportToCsv_Click(object sender, EventArgs e) => ExportPacketsAsCsv();

        private void btnExportBytesFromSelected_Click(object sender, EventArgs e) => ExportSelectedPacketAsBinary();

        private void MyToolbar_ItemClicked(object sender, ToolStripItemClickedEventArgs e)
        {

        }

        private void DGV_CellContentClick(object sender, DataGridViewCellEventArgs e)
        {

        }

        private void CbInterfaces_SelectedIndexChanged(object sender, EventArgs e)
        {

        }
    }
}