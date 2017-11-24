
rule n2321_3b1b35b9c6620b16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n2321.3b1b35b9c6620b16"
     cluster="n2321.3b1b35b9c6620b16"
     cluster_size="5"
     filetype = "PE32 executable (GUI) Intel 80386 (stripped to external PDB)"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="amonetize cqhj classic"
     md5_hashes="['407a68bbfd1fa439b3064b8ecd2c08bc','52fe8526bf41e370342f1003b9b801af','e875b1b3c38e79069f91ce87ec2abccf']"

   strings:
      $hex_string = { 81fe6f98db5aaafdcf9e660183519569166eae109b04734ad5e2a5bf0abd92d23465f1e38d1b9353f4e4dc263bab3fdf2be9f09d3d6aa3f77cdae8f91c450541 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
