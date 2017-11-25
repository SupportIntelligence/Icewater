
rule k3f4_27507e81c8000332
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3f4.27507e81c8000332"
     cluster="k3f4.27507e81c8000332"
     cluster_size="51"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="bladabindi backdoor disfa"
     md5_hashes="['088cdbbac16837e9f8a8d03edc308857','0be69d37d36aa4a38e1f88e7434cca1f','5d61320127d6dd92af0ab4f03ff1b37c']"

   strings:
      $hex_string = { 7472794b65795065726d697373696f6e436865636b0047657456616c75654e616d6573006765745f4c656e67746800436f6e7665727400546f42617365363453 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
