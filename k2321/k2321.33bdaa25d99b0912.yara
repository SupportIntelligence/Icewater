
rule k2321_33bdaa25d99b0912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.33bdaa25d99b0912"
     cluster="k2321.33bdaa25d99b0912"
     cluster_size="33"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="antavmu fileinfector moctezuma"
     md5_hashes="['00b9996972c094111f05dc1f2d5a8046','0373bfe4a09d60ac4136ccbdab374536','692a6b10db1698b88df1da81a1cc020c']"

   strings:
      $hex_string = { 8385bf4400744d363941cc35c0def57162c1c23a2814be4ffc98c77b8c077b3cc9e63b025cd1ef75edff27321dcdd494e9aeff49a6f7ec31f25548e419fa6d23 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
