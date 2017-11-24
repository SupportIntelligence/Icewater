
rule j3e9_46b25c99c6220912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j3e9.46b25c99c6220912"
     cluster="j3e9.46b25c99c6220912"
     cluster_size="9"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="backdoor poison poisonivy"
     md5_hashes="['97da683e7c0ac875a9919bc7d3627a4e','a1cac5b71c982017660b2fac497bcd38','ded59a8974b8110e94db4c3f4e49d9cf']"

   strings:
      $hex_string = { 5ec50b1aa6e139cad5475d3dd9015ad651566c4d8b0d9a66fbccb02d74122b20f0b18499df4ccbc2347e76056db7a931d11704d714583a61de1b111c320f9c16 }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
