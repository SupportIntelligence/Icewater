
rule m3e9_71562d10db1f4b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.71562d10db1f4b12"
     cluster="m3e9.71562d10db1f4b12"
     cluster_size="76"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171121"
     license = "RIL-1.0 [Rick's Internet License] "
     family="vobfus chinky jorik"
     md5_hashes="['2e3661e1c1985684c87dcdf0118ebe7b','37808c1a1e729b5fb682ff1dbd6b1c5c','a5f6fd4987bc01a36d935ff42c58cccc']"

   strings:
      $hex_string = { c683e0018945fc83e6fe568975088b0eff510433db895de8895de4e82f0cfeff8b3d90104000ffd78b168d45e85056ff52583bc3dbe27d0f6a5868b061400056 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
