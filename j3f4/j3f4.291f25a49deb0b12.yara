
rule j3f4_291f25a49deb0b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j3f4.291f25a49deb0b12"
     cluster="j3f4.291f25a49deb0b12"
     cluster_size="3"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="dotdo malicious attribute"
     md5_hashes="['33ca467ab518fdfe819cc4ea8799e97c','99a789d121675b161b8634ab2f25c88b','db5cc06a11e67802e4890453283c1cb9']"

   strings:
      $hex_string = { 3c737570706f727465644f532049643d227b33353133386239612d356439362d346662642d386532642d6132343430323235663933617d222f3e2d2d3e0d0a0d }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
