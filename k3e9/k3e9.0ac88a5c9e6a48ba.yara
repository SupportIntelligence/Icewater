
rule k3e9_0ac88a5c9e6a48ba
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.0ac88a5c9e6a48ba"
     cluster="k3e9.0ac88a5c9e6a48ba"
     cluster_size="4"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="tinba zusy backdoor"
     md5_hashes="['5ee0de83ae7b1da3e0da5402b70f95c1','6a94d7165a9b6668b7cc56274bad716b','8f099e8a65dc8b6020f46c212f5cd8b6']"

   strings:
      $hex_string = { 6b867931abbd5924e0bb284f091fb67433c6297c582e00a119414065a0445bacd30d5e6deca678af6c1b7d21f9f594fea32ac70eed8903a9ad277162738ea8c9 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
