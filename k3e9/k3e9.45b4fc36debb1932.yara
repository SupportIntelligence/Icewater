
rule k3e9_45b4fc36debb1932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.45b4fc36debb1932"
     cluster="k3e9.45b4fc36debb1932"
     cluster_size="36"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171111"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virut virtob classic"
     md5_hashes="['06ba887e52c7b85f598b047c7747dedd','203e916de7971561287f8e8e6007db1d','7c7210d4965d924738558efdabcb62c4']"

   strings:
      $hex_string = { 74128a5e018ad33a5901750c4646414184d275e233c9eb051bc983d9ff85c9750c8a4f048b54241033c040880a83c7088b0f80390075b45e5b5fc20400813df8 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
