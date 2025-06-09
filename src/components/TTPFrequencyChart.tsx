import React from 'react';
import { Bar } from 'react-chartjs-2';
import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  BarElement,
  Title,
  Tooltip,
  Legend,
} from 'chart.js';
import type { TtpFrequencyData } from '../hooks/useApi'; // Assuming TtpFrequencyData is exported from useApi

ChartJS.register(
  CategoryScale,
  LinearScale,
  BarElement,
  Title,
  Tooltip,
  Legend
);

interface TTPFrequencyChartProps {
  frequencyData: TtpFrequencyData | null;
  loading: boolean;
  error: string | null;
}

const TTPFrequencyChart: React.FC<TTPFrequencyChartProps> = ({ frequencyData, loading, error }) => {
  if (loading) {
    return <div className="text-center p-4">Loading TTP frequency data...</div>;
  }

  if (error) {
    return <div className="text-center p-4 text-red-600">Error loading TTP data: {error}</div>;
  }

  if (!frequencyData || Object.keys(frequencyData).length === 0) {
    return <div className="text-center p-4 text-gray-500">No TTP frequency data available to display.</div>;
  }

  // Prepare data for the chart
  const labels = Object.keys(frequencyData);
  const dataValues = Object.values(frequencyData);

  const chartData = {
    labels,
    datasets: [
      {
        label: 'TTP Frequency',
        data: dataValues,
        backgroundColor: 'rgba(54, 162, 235, 0.6)', // Blue color
        borderColor: 'rgba(54, 162, 235, 1)',
        borderWidth: 1,
      },
    ],
  };

  const options = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: {
        position: 'top' as const,
      },
      title: {
        display: true,
        text: 'MITRE ATT&CK TTP Frequency',
      },
      tooltip: {
        callbacks: {
          label: function(context: any) {
            let label = context.dataset.label || '';
            if (label) {
              label += ': ';
            }
            if (context.parsed.y !== null) {
              label += context.parsed.y;
            }
            return label;
          }
        }
      }
    },
    scales: {
      y: {
        beginAtZero: true,
        ticks: {
          stepSize: 1, // Ensure y-axis ticks are integers for counts
        }
      },
      x: {
        title: {
            display: true,
            text: 'MITRE TTP ID'
        }
      }
    },
  };

  return (
    <div className="p-4 bg-white rounded-lg shadow" style={{ height: '400px' }}> {/* Added fixed height for chart container */}
      <Bar options={options} data={chartData} />
    </div>
  );
};

export default TTPFrequencyChart; 