
rule k231b_49958eaccfeb0912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k231b.49958eaccfeb0912"
     cluster="k231b.49958eaccfeb0912"
     cluster_size="75"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="faceliker script autolike"
     md5_hashes="['3c61e4c27c19d3134270ac97bfaadf8952b78c35','4ab64e31da6bfb378c512864acc76ba7c6129807','2698e1edd047edf472efa07f3c16b99e6ed02b9e']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k231b.49958eaccfeb0912"

   strings:
      $hex_string = { 2a205374796c653a20274d264d273b205374796c652049443a2036360d0a2a2f0d0a626f64790d0a7b0d0a096261636b67726f756e643a20234537463343343b }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
