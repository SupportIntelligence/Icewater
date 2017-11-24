
rule k2321_33bdaa25db9b0912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.33bdaa25db9b0912"
     cluster="k2321.33bdaa25db9b0912"
     cluster_size="28"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="antavmu fileinfector squdf"
     md5_hashes="['1f23fd35c58afa01a4af29245d26f590','206dd359b9b962a036b61d079f72eb10','a4d8533d1c51ed94fd76b2d519786b20']"

   strings:
      $hex_string = { 8385bf4400744d363941cc35c0def57162c1c23a2814be4ffc98c77b8c077b3cc9e63b025cd1ef75edff27321dcdd494e9aeff49a6f7ec31f25548e419fa6d23 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
