
rule j2321_30bb100208001912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j2321.30bb100208001912"
     cluster="j2321.30bb100208001912"
     cluster_size="15"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171124"
     license = "RIL-1.0 [Rick's Internet License] "
     family="backdoor cosmicduke razy"
     md5_hashes="['19b9a1b577cde16483c2ae52e2b42b15','1e8b2fc531c81b7ede481ab3d44d92cb','fce78b38e8c50dc23e1aebc61ae049f2']"

   strings:
      $hex_string = { 406978ace3aeee91beb1f181d178a8b725eb8647c74b1bfa46760d9792fb0bdbb6143675dcb57cd7f070f62f6abd5d77a9fcc4607f36dbde7af45cc15ca3e483 }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
