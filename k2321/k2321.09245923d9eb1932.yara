
rule k2321_09245923d9eb1932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.09245923d9eb1932"
     cluster="k2321.09245923d9eb1932"
     cluster_size="6"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="vobfus conjar autorun"
     md5_hashes="['2a0de36eb91597d57834a3c617cd494b','5faa409d9dac8663e838c792a34a1aa5','f67dd874b22d3bd75dfff982c39e51b9']"

   strings:
      $hex_string = { 21aa817cb72816db9fc9c222ac9136554726ccf7b9bf8d447a278400d9b63761ec1f3477d9f6e3d682a7c5dca16ba63d8746657792c05f1139d54c4bb0a2e41a }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
