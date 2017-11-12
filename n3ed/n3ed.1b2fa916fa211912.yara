
rule n3ed_1b2fa916fa211912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3ed.1b2fa916fa211912"
     cluster="n3ed.1b2fa916fa211912"
     cluster_size="17"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171111"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit nimnul bqjjnb"
     md5_hashes="['0fd08bf6b6d14c561459b8a959ce5c92','4565e4cca47c9a8c81bec841081c8fa6','dd62f537b03deea1c05126b48d0bc940']"

   strings:
      $hex_string = { 82b940bf3cd5a6cfff491f78c2d3406fc6e08ce980c947ba93a841bc856b5527398df770e07c42bcdd8edef99dfbeb7eaa5143a1e676e3ccf2292f8481264428 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
