package com.oguzhanstech.hybridvpn

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import com.oguzhanstech.hybridvpn.ui.AppRoot
import com.oguzhanstech.hybridvpn.ui.theme.HybridVPNTheme

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContent {
            HybridVPNTheme {
                AppRoot()
            }
        }
    }
}
