
rule j3f4_23a0d5e9c8800112
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j3f4.23a0d5e9c8800112"
     cluster="j3f4.23a0d5e9c8800112"
     cluster_size="18"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="dotdo engine malicious"
     md5_hashes="['0076876b6bffd9115f94e6da5d360ffb','1bbd45be47cef7a6d7e5cd53b5b5dfde','eb721f45a8b1e125bd392d82c965d40f']"

   strings:
      $hex_string = { 3c737570706f727465644f532049643d227b33353133386239612d356439362d346662642d386532642d6132343430323235663933617d222f3e2d2d3e0d0a0d }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
