
rule j26bf_14a85eb91ac31130
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j26bf.14a85eb91ac31130"
     cluster="j26bf.14a85eb91ac31130"
     cluster_size="173"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="razy malicious onlinegames"
     md5_hashes="['687ddebf28532bc48f84eb70eacfa2f696175293','31ef4ecc3333b71993ee8ff23fb8e844fbaa288d','537aaef6136a10ffcee2600ec3f797deb331f5c0']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=j26bf.14a85eb91ac31130"

   strings:
      $hex_string = { 11157519000001131711172c0711176f2500000adc111417581314111411138e693f8ffeffff083979feffffdd5b020000261f1c282600000a72930300707320 }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
