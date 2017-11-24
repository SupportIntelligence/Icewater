
rule n2321_399a1199c6620b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n2321.399a1199c6620b32"
     cluster="n2321.399a1199c6620b32"
     cluster_size="237"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="amonetize genericrxdd aqqy"
     md5_hashes="['004afe5ad7be6e7fe2c98c3e5bfaae2f','00aa2e0640359959da211c5bde55e275','12cceb6e1732a6ab588ec986822da002']"

   strings:
      $hex_string = { 6a9782b290400457b3f656944ef755a4065189340378ef2dccdeabd03d5a05bf4b2fb9c1f9ea763937591620489571e5d61a3efee8745fc0bb1c354a28196529 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
