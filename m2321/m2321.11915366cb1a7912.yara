
rule m2321_11915366cb1a7912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.11915366cb1a7912"
     cluster="m2321.11915366cb1a7912"
     cluster_size="8"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="scar zusy scudy"
     md5_hashes="['2bd561a65e365e90bd94d5281248f8ab','3f19dbb744bced958061feb5955df8e5','bc7853b9f63246d96bf2c935b0bc55c2']"

   strings:
      $hex_string = { b45d877aa03a8c8c6fd0a50323a1c55bb87f3244ea2f07bdfa4f795e8b47b1fed1ce5a64b3be097d398d762da8fbdd2e9b33167b58311eee616d94bb789201b6 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
