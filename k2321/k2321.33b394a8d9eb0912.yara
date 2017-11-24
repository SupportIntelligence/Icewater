
rule k2321_33b394a8d9eb0912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.33b394a8d9eb0912"
     cluster="k2321.33b394a8d9eb0912"
     cluster_size="34"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="androidos smssend andr"
     md5_hashes="['00483edb3cc591ed0b8a1b03aca99e7d','03b5d030a2d1a86cb6af3d00e68cbf00','7e79af7f090c6af65d2274da0b8ef8e5']"

   strings:
      $hex_string = { 79e6e2bbb0f722e3a48f998dbe6a091508fa09196642789776a318e921b1d65eadb98312421bf2a5779c34326240b81eb6a00226c129ed4661bc03715f90d5a7 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
