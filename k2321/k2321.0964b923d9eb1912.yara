
rule k2321_0964b923d9eb1912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.0964b923d9eb1912"
     cluster="k2321.0964b923d9eb1912"
     cluster_size="5"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="vobfus conjar autorun"
     md5_hashes="['079a76ff76e12983dac26fc99b46ff5a','3caf24f7965c27e39a31793276f45ca4','78df23271c0b59b8a4fe198533f94468']"

   strings:
      $hex_string = { 70cc124dfe0a164590f6cbf257312cdb7bcc39d4ed1ef90a585f6776a2a3852650b95dbe8b81d3ab8fd983df9efc01250d4440144a52ad21555a7da993095688 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
