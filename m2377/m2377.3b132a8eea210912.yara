
rule m2377_3b132a8eea210912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2377.3b132a8eea210912"
     cluster="m2377.3b132a8eea210912"
     cluster_size="4"
     filetype = "HTML document"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="clicker faceliker script"
     md5_hashes="['13ae4f9461b1ae4f6e31bf1ec10a36a9','35c7831db6f2f2bbaff0271c50d642e6','fe18b15784f68bdee2310dbcafa5822f']"

   strings:
      $hex_string = { 78473757525133355653342f7337322d632f486172726965745f5475626d616e5f66616d6f75735f626c61636b5f70656f706c652e6a7067272077696474683d }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
