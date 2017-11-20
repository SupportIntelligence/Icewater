
rule m3e9_491c97a9c9000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.491c97a9c9000b12"
     cluster="m3e9.491c97a9c9000b12"
     cluster_size="10"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="kazy mewsspy nionspy"
     md5_hashes="['06ff28b149fc67ae650c02b7ca8eff1a','1412f084ba98e77a052dc8afee0b1d33','8a1f852da73615b67b85b021ea83250e']"

   strings:
      $hex_string = { 72e648c819998ab2344555d3ca87df825bec9f1fef0812b5ba222dc69af5c7d7aec34bfda8ff6e719b0a5d95ab629ed8a56cb01dc230b83c85fb07662e9da16a }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
