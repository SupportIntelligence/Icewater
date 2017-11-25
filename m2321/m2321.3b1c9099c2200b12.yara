
rule m2321_3b1c9099c2200b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.3b1c9099c2200b12"
     cluster="m2321.3b1c9099c2200b12"
     cluster_size="9"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171121"
     license = "RIL-1.0 [Rick's Internet License] "
     family="otwycal wapomi vjadtre"
     md5_hashes="['13da022b8389a7d2cdeb389ef835e633','354ae3f33d7bb1f61f89a597a16a74aa','f6049549810fb0e7cf2a45e7e058ffc5']"

   strings:
      $hex_string = { fb090b36b3b2216439bc23d374fea1d85640f098776bab84db17f5e1d959cfe369bf2fe45533c11fda45f1155c0866ba945fa325ae0a4663c787505a8f08d54f }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
