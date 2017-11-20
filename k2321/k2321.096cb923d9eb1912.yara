
rule k2321_096cb923d9eb1912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.096cb923d9eb1912"
     cluster="k2321.096cb923d9eb1912"
     cluster_size="4"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="vobfus conjar autorun"
     md5_hashes="['4de5ef5b2c3ec23996075642b695e1fe','534f78e57e3cb8961ffc727b21297da5','da51c7954ab644b5559778eb245c0444']"

   strings:
      $hex_string = { 70cc124dfe0a164590f6cbf257312cdb7bcc39d4ed1ef90a585f6776a2a3852650b95dbe8b81d3ab8fd983df9efc01250d4440144a52ad21555a7da993095688 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
