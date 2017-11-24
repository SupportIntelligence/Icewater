
rule m3e9_267e235bc6a30b16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.267e235bc6a30b16"
     cluster="m3e9.267e235bc6a30b16"
     cluster_size="61"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="amku malicious risktool"
     md5_hashes="['01121d9f8d45f1ef1ab2557ca0e8e13d','075353207afb055d68ef659d539e8175','41c17712aacf152270007b9a93359653']"

   strings:
      $hex_string = { 6c4ea8235377b7083616793f6ddbc037d5ab5e82c6e97fde0b8f9bc166f364a4a9950348f5cbfa068bbd88094cb650cdf9380f4aff61ecf68ab5591c1878eb3c }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
