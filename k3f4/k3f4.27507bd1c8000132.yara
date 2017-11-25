
rule k3f4_27507bd1c8000132
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3f4.27507bd1c8000132"
     cluster="k3f4.27507bd1c8000132"
     cluster_size="20"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="bladabindi backdoor malicious"
     md5_hashes="['1353583ba05e993f5bb0ea3f1a349790','1ec3a4c851738c677600b177ba590c87','c315e7a2ce007979c4b71307839b91da']"

   strings:
      $hex_string = { 7472794b65795065726d697373696f6e436865636b0047657456616c75654e616d6573006765745f4c656e67746800436f6e7665727400546f42617365363453 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
