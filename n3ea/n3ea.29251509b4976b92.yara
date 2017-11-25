
rule n3ea_29251509b4976b92
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3ea.29251509b4976b92"
     cluster="n3ea.29251509b4976b92"
     cluster_size="423"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="smspay androidos riskware"
     md5_hashes="['003263d20c1b7f083b0cbd9ecae8f200','021f44237435ee0b156b3b20f43529e6','0a0bdb7a1f9b0b37192ae4eb9f456a4b']"

   strings:
      $hex_string = { 1f5a895e4696d4690a1acba4a3932dc1ea10df447eaaac9523af2e5d5ca57be8274ccde3f480d9ed7aef8240f5879c1ee07f429fb330583d9d0dccd2593e7416 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
