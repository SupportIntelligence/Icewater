
rule k3f4_235079d1c8000330
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3f4.235079d1c8000330"
     cluster="k3f4.235079d1c8000330"
     cluster_size="2053"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="bladabindi backdoor malicious"
     md5_hashes="['000073ea4284e5c5b6187a536975f13a','00213364a2481e29707794e77b92e5bb','01963c6a4655bf3407e0b15fe00472ed']"

   strings:
      $hex_string = { 7472794b65795065726d697373696f6e436865636b0047657456616c75654e616d6573006765745f4c656e67746800436f6e7665727400546f42617365363453 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
