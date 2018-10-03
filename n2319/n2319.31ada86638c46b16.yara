
rule n2319_31ada86638c46b16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n2319.31ada86638c46b16"
     cluster="n2319.31ada86638c46b16"
     cluster_size="3"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="coinminer cryxos miner"
     md5_hashes="['4b64d1a3a4f44e3529fe31f76750a1dd495aa993','5532fae49b9b8c7a0feb4bc100eb32be36338dcd','1d78354e189eb7fba4d764c295a499665174acc5']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n2319.31ada86638c46b16"

   strings:
      $hex_string = { 313032343b766172204d41585f5441424c455f53495a453d4d6f64756c655b5c227761736d4d61785461626c6553697a655c225d3b696628747970656f662057 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
