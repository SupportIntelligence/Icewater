
rule k3e9_4324f8569ebb1912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.4324f8569ebb1912"
     cluster="k3e9.4324f8569ebb1912"
     cluster_size="149"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virut virtob virux"
     md5_hashes="['021d073ffd15d9238f8996abc93085be','0835bd9ca828d23264726d6a2ea61291','71c938b2dd0090de480d848953630b6c']"

   strings:
      $hex_string = { f7de1bf646837df8007409ff75f8ff150c1000018bc6eb0233c05f5e5bc9c20400cccccccccc8bff558bec81ec1c020000a1f0600001538b5d08578945fc8d85 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
