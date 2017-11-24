
rule m3e9_5096b3e9c8800b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.5096b3e9c8800b32"
     cluster="m3e9.5096b3e9c8800b32"
     cluster_size="53"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="vobfus barys jorik"
     md5_hashes="['0e2b394373063663d24da1ea9680c959','2ab667cc37fa4c6f36fc17fb4eefb5ff','b6f6392f59046f20649397affe77c86d']"

   strings:
      $hex_string = { 384f36585ea7c9cfc376345652565715325467a8dfdadbed4327000000000000000000000000a4fefffaff03ffcdfde49f5f443e958e97aed2f9ae2552523501 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
