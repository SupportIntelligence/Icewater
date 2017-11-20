
rule k3f4_275079d1c8000332
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3f4.275079d1c8000332"
     cluster="k3f4.275079d1c8000332"
     cluster_size="549"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="bladabindi backdoor bkdr"
     md5_hashes="['008b892acdadf7fb6851f09b57eea300','00df774ceae488abca92b6ed0dd84dbf','0b51ddabc2913c5d4e8cdf31ad59ae67']"

   strings:
      $hex_string = { 7472794b65795065726d697373696f6e436865636b0047657456616c75654e616d6573006765745f4c656e67746800436f6e7665727400546f42617365363453 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
