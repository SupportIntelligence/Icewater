
rule k3e9_1f4efcc1c8000112
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.1f4efcc1c8000112"
     cluster="k3e9.1f4efcc1c8000112"
     cluster_size="60365"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="upatre generickd archsms"
     md5_hashes="['00026ceb6e105788787c418fe0049e85','0004578c1ac9bfa5c6aae029ab513f58','001cf667ce813bead5eb2e0b9a745a02']"

   strings:
      $hex_string = { 7c8ae1721c734f67bf06cb65eee1a977a6b6ec8d1bdc99ca28460417c2352600dccef3219c1356e6cc40bc311658224339d65732813dfc9f89c52bc3c608e2fd }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
