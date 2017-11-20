
rule m2377_589b3929c8000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2377.589b3929c8000b12"
     cluster="m2377.589b3929c8000b12"
     cluster_size="35"
     filetype = "HTML document"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit html script"
     md5_hashes="['029acb83a68c820492c2bf1336b7109c','04512a9c602b1cf34bf79493c01def20','6052503133180c39c51e364631e4ea3a']"

   strings:
      $hex_string = { 8f79d06431549be714dfd3b64360182b8c04db0ceeb00a92b3a92a3ecce6991ef3807a1509fcf03916f155e281d3673d5b72d62c4036453cf501fb30ed57717e }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
