
rule m3e9_33b996d3c9ad9b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.33b996d3c9ad9b12"
     cluster="m3e9.33b996d3c9ad9b12"
     cluster_size="24"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="juched zusy ganelp"
     md5_hashes="['040895b74131c38542d6a45fcb85c986','135b6fef18e69585859b88e50c77aec3','daaf013ec7ce4d3e7dae80eaa5061e47']"

   strings:
      $hex_string = { 8847018a46028847028b45085e5fc9c3908d7431fc8d7c39fcf7c7030000007524c1e90283e20383f908720dfdf3a5fcff2495300c41008bfff7d9ff248de00b }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
