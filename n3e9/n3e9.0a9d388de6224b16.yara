
rule n3e9_0a9d388de6224b16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.0a9d388de6224b16"
     cluster="n3e9.0a9d388de6224b16"
     cluster_size="5280"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="scar zusy genome"
     md5_hashes="['000b2ddb3341e82acfb863b7cfadcc22','002bcc98cef9510604dc0c29d6b98ea6','0385849aa2493d1c6582dfcb2ea7f77d']"

   strings:
      $hex_string = { 8cc5001f9acc0020a3d10022a7d2003ab5da002fa9e20048cae3001ec1ea0023d6ea008ee9ed0072e6f1008de8f3007bf3f8007bf5f8007cf5f8007cf6f8007e }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
