
rule k2319_690eb949c8000912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.690eb949c8000912"
     cluster="k2319.690eb949c8000912"
     cluster_size="27"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="multiplug script browext"
     md5_hashes="['4d9ebfea5e2b2a50596225c4fbee0ef937b47610','597c92b4b88f5b8acb79cd1da3c6901b16008678','9acf9ecbf78ad1a862ef7f5cb516eb2e46e02743']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.690eb949c8000912"

   strings:
      $hex_string = { 44333d66756e6374696f6e2862297b76617220423d27223b7d273b76617220643d273d22273b76617220653d2835302e3c3d28307842382c332e36354532293f }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
