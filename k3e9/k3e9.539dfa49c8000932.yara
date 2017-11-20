
rule k3e9_539dfa49c8000932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.539dfa49c8000932"
     cluster="k3e9.539dfa49c8000932"
     cluster_size="73"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="nitol bmgfamexfyfb networkworm"
     md5_hashes="['0705ad77a7bbd261fa214587844f83cb','0a4bbda442559e9fafffaf8de1c7feb6','5419047216df33bd938cad9007fd1af2']"

   strings:
      $hex_string = { 53484c574150492e646c6c005553455233322e646c6c005753325f33322e646c6c0000004c6f61644c69627261727941000047657450726f6341646472657373 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
