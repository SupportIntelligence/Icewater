
rule n3e7_2cc612f651ab10c9
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e7.2cc612f651ab10c9"
     cluster="n3e7.2cc612f651ab10c9"
     cluster_size="34"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit nimnul malicious"
     md5_hashes="['1202895534f313ac758d5016a06e62f3','448a5bc3fb24ac95497b8f4f76ec77a6','abf5c1832073e87e9acb14628a2920d9']"

   strings:
      $hex_string = { 7f00ffcc820cffcb9740ffcfae76ffd3c0a0ffd7d2caffd9d9d9ffdadadaffdadadaffdadadaffd8d8d8ffd4c6aeffd0b384ffcc9d4effc9810cffc97d00ffc8 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
