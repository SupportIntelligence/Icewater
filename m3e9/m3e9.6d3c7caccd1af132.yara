
rule m3e9_6d3c7caccd1af132
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.6d3c7caccd1af132"
     cluster="m3e9.6d3c7caccd1af132"
     cluster_size="142"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="vobfus graftor wbna"
     md5_hashes="['0085c9034d891fcc502bf84abcabab67','0505ec9cd947dd260d44d3773eaff95d','3cc9f26a4335e9dedfe6aa9f0ebff9e6']"

   strings:
      $hex_string = { 8cc1e0048b0d2040430003c8e85e7cfeff68bdbe4100eb258b45f083e00485c074088d4dd0e8697cfeff8d45b0508d45c0506a02e8127cfeff83c40cc3c38d75 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
