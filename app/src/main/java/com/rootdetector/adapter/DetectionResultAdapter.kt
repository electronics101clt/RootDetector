package com.rootdetector.adapter

import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.ImageView
import android.widget.TextView
import androidx.recyclerview.widget.DiffUtil
import androidx.recyclerview.widget.ListAdapter
import androidx.recyclerview.widget.RecyclerView
import com.rootdetector.DetectionResult
import com.rootdetector.R
import com.rootdetector.Severity

/**
 * RecyclerView adapter for displaying detection results
 */
class DetectionResultAdapter : ListAdapter<DetectionResult, DetectionResultAdapter.ViewHolder>(
    DetectionResultDiffCallback()
) {

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): ViewHolder {
        val view = LayoutInflater.from(parent.context)
            .inflate(R.layout.item_detection_result, parent, false)
        return ViewHolder(view)
    }

    override fun onBindViewHolder(holder: ViewHolder, position: Int) {
        holder.bind(getItem(position))
    }

    class ViewHolder(itemView: View) : RecyclerView.ViewHolder(itemView) {
        private val iconView: ImageView = itemView.findViewById(R.id.resultIcon)
        private val titleView: TextView = itemView.findViewById(R.id.resultTitle)
        private val detailsView: TextView = itemView.findViewById(R.id.resultDetails)

        fun bind(result: DetectionResult) {
            titleView.text = result.checkName
            detailsView.text = result.details

            // Set icon based on severity
            val (iconRes, iconColor) = when (result.severity) {
                Severity.SUCCESS -> Pair(R.drawable.ic_check_green, R.color.success_green)
                Severity.WARNING -> Pair(R.drawable.ic_warning_yellow, R.color.warning_yellow)
                Severity.CRITICAL -> Pair(R.drawable.ic_cross_red, R.color.critical_red)
            }

            iconView.setImageResource(iconRes)
            iconView.setColorFilter(itemView.context.getColor(iconColor))
        }
    }

    private class DetectionResultDiffCallback : DiffUtil.ItemCallback<DetectionResult>() {
        override fun areItemsTheSame(oldItem: DetectionResult, newItem: DetectionResult): Boolean {
            return oldItem.checkName == newItem.checkName
        }

        override fun areContentsTheSame(oldItem: DetectionResult, newItem: DetectionResult): Boolean {
            return oldItem == newItem
        }
    }
}
