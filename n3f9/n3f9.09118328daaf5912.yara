
rule n3f9_09118328daaf5912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3f9.09118328daaf5912"
     cluster="n3f9.09118328daaf5912"
     cluster_size="78"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171109"
     license = "RIL-1.0 [Rick's Internet License] "
     family="airadinstaller airinstaller bundler"
     md5_hashes="['09b3a829f804102766251d383c9320a8','146649c7479ee10d037fe99cb72eb5d5','5fad69b2a5c9284a267e4a67d2197f55']"

   strings:
      $hex_string = { dee3400f8eac743c4b53fd21d51512fbc9b6b930bd018d510f8588c9ec00ebd2f08f2f45646a3ab6c0f9e6552439bed5c8cfcab47ed09f84c980e705c36665fd }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
