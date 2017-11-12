
rule n3ed_114331e9ca000912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3ed.114331e9ca000912"
     cluster="n3ed.114331e9ca000912"
     cluster_size="5"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171111"
     license = "RIL-1.0 [Rick's Internet License] "
     family="symmi banhguo lmir"
     md5_hashes="['3b70431b52e11144b2d372b1508f01cf','5ccbef30a204c7fc80f487b3a894fbe6','da99af2dfe288e5cfdd78a6b75244652']"

   strings:
      $hex_string = { 36a52bd9eb538074637fc9e452a91bf10c3a62e0e53c39903237e3343369c58669c23587e22175a1a06e144017a38c0af25bdf8347bc23feec64558bac248491 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
