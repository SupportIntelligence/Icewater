
rule m2321_5b191710dee30912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.5b191710dee30912"
     cluster="m2321.5b191710dee30912"
     cluster_size="7"
     filetype = "MS-DOS executable (gzip compressed data"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171121"
     license = "RIL-1.0 [Rick's Internet License] "
     family="enistery emotet pemalform"
     md5_hashes="['0941077a122338407042b0c8b278f6d4','0f63dc5d026c75b7f1643990bb6ee7fa','ece82d4a7e4366629201ce6803ff23d1']"

   strings:
      $hex_string = { 31d7f800a77212b999f91de17754f5257d2cc12042f10d753a32436fcba6053f914c98e487a4e97641fc649fae5636d6c41557e6cfd25e5fd166b782134f7e90 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
