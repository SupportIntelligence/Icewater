
rule m3e9_613c945b16d30b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.613c945b16d30b32"
     cluster="m3e9.613c945b16d30b32"
     cluster_size="89"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="vbkrypt vobfus wbna"
     md5_hashes="['0689dac8393b2230690962329c64342c','0fd7d1c437b2035581f20e6e04999e99','a0e35780d8f93bd68a80301ac9593d4b']"

   strings:
      $hex_string = { dd05181740005151dd1c24e864d1feffdd9d64ffffff9b6870674100eb298b45f083e00485c074088d4dd8e892d1feff8d45a8508d45b8508d45c8506a03e8c1 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
