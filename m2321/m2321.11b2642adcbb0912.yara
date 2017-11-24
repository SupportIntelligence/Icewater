
rule m2321_11b2642adcbb0912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.11b2642adcbb0912"
     cluster="m2321.11b2642adcbb0912"
     cluster_size="135"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="backdoor elzob shiz"
     md5_hashes="['005ae3c8ee494325eb63af73d6c58045','0244a32e6f8b20295708353a2fe85489','16c344ef4a538453f4f2802df80cf6c1']"

   strings:
      $hex_string = { 3108ecbabb14667399ab5479169b5b56aefe978eee545e03c121c7a590231bd2b94a65eab1d6433d2b37692767e69ad978d75f021af592393a95ffc474da19b0 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
