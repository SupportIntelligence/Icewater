
rule n3e9_31ca92afc6220932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.31ca92afc6220932"
     cluster="n3e9.31ca92afc6220932"
     cluster_size="6"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171109"
     license = "RIL-1.0 [Rick's Internet License] "
     family="zusy cuegoe malicious"
     md5_hashes="['3905f456ca979b9584a81064a151e51a','52630190062ce0bd83f07d36e32c96eb','d9f46951ecd0430a2ceb1496169385ac']"

   strings:
      $hex_string = { 91c176c4c24d183198266d3721bdba4a47026a05dbe803264dc5f00d0118a9f3bc565b4d165a93c1c817a051fd05a8aef6b2ff1f00d2ebb51dc8e2576472455c }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
