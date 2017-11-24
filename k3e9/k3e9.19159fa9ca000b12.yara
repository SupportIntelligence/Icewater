
rule k3e9_19159fa9ca000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.19159fa9ca000b12"
     cluster="k3e9.19159fa9ca000b12"
     cluster_size="17"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="nimnul vjadtre small"
     md5_hashes="['0fd58d6851d1e8693d6a1b6ed9e76fd6','19a62f52006f633823cbb92eaa56f8b5','f58d578aee32857050bed12e0e64109b']"

   strings:
      $hex_string = { 5ad9a8294361ed987068f769715e671136138f83339792073e2531f29a1db07d12a8322a76b887c26489aa5c0d2ee76b0927d7ad78a6ffd4246d21c97ed0a9f5 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
