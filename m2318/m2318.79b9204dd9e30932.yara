
rule m2318_79b9204dd9e30932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2318.79b9204dd9e30932"
     cluster="m2318.79b9204dd9e30932"
     cluster_size="4"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit html script"
     md5_hashes="['72344ee2de95fe648f14a77d0c72d8c0','a945ce89b54817592c54919936117cf8','e1e3389fa234db3dd37a61de4accbd2e']"

   strings:
      $hex_string = { 46444144393644383433433035463733423743364530423431333730433141393035363841323139363937323739324538454532424631304235343746344243 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
