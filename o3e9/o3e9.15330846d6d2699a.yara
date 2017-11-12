
rule o3e9_15330846d6d2699a
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.15330846d6d2699a"
     cluster="o3e9.15330846d6d2699a"
     cluster_size="530"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171109"
     license = "RIL-1.0 [Rick's Internet License] "
     family="installmonster installmonstr malicious"
     md5_hashes="['006dac68b62ec59acaebadaeb93ff835','007607761c2f4f4316dadee80afdd287','04de904f819634e72eeed0ed2ecb305d']"

   strings:
      $hex_string = { b6181241f1a961799d06475059ab853b3c4d845f6919182cde7a03912dbe722b9a30488ff8d307bd1d1b219b66f71e9352b6c7cad6c97ce9dc3262c67db50db3 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
