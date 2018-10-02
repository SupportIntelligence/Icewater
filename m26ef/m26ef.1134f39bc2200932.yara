
rule m26ef_1134f39bc2200932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m26ef.1134f39bc2200932"
     cluster="m26ef.1134f39bc2200932"
     cluster_size="48"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="razy diztakun heuristic"
     md5_hashes="['fe8cf569d0b7bdca309e8b7da82a102de717f917','92ab10a2ba443d59a5378c8c37c06e1fea5783a6','62b9d958c72cccea7a414f99fd6c9c0cc570641b']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m26ef.1134f39bc2200932"

   strings:
      $hex_string = { c438c3cccc44894c24204489442418535556574154415641574883ec3033c04983cfff488bf2488bd94885c97412498bef0f1f400048ffc56639046975f7eb02 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
